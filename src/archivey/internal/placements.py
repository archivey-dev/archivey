"""Which result of an extraction run owns each file the run put on disk.

The run's report says what happened to each member. This record answers a different
question: which write owns the directory entry at a destination now. The two differ
under ``ExtractionPolicy.TRUSTED``, where an earlier result keeps its path after a
later member replaced its file, so the report cannot tell the coordinator who owns
a file.

Claims are kept by collision key (the coordinator's ``_collision_key``: the parent
resolved, the name folded unless TRUSTED) and by the claimed file's identity on disk
(``st_dev``, ``st_ino``). The filesystem decides whether two spellings reach the same
entry: :meth:`Placements.owner` asks it, and :meth:`Placements.land` retires the claim
of the file a landing replaced, so a stale claim never answers for a file that is gone.

Paths are compared as spelled (``os.fspath``), never with ``Path`` equality:
``WindowsPath`` equality folds case, and a case variant of a claimed name is one of
the spellings this record has to keep apart.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from archivey.internal.filters import collision_key
from archivey.internal.long_paths import long_path
from archivey.types import ExtractionPolicy


@dataclass(frozen=True)
class Claim:
    """A destination claimed by a member written this run, with the index of that
    member's result. A later ``REPLACE`` onto the destination revises that result.

    ``physical`` is where the claimed file was when it was claimed, with every parent
    resolved. The key is taken from it, and a collision is routed to it. ``path`` can
    run through a caller's symlink that a later member replaces, so it can stop naming
    that file. ``key`` is the collision key it was claimed under.
    """

    path: Path
    result_index: int
    physical: Path
    key: str


def _same_spelling(a: Path, b: Path) -> bool:
    return os.fspath(a) == os.fspath(b)


@dataclass
class Placements:
    """The live claims of one run, by collision key and by file identity.

    A claim is live while ``by_key`` holds it under its own key. The identity index
    is filled lazily: a claim waits in ``_unindexed`` until the first identity lookup
    after it was made, so a run into an empty destination costs no ``lstat``. An
    identity hit is checked again against the claimed path, as an inode can be reused
    once its file is gone. One inode can hold several claims: an archive's hard link
    gives its file a second name.
    """

    by_key: dict[str, Claim] = field(default_factory=dict)
    # The key each claimed path was claimed under, by spelling, so a release finds the
    # claim after a symlink in its path was replaced and the path resolves elsewhere.
    _key_of: dict[str, str] = field(default_factory=dict)
    _by_id: dict[tuple[int, int], list[Claim]] = field(default_factory=dict)
    _unindexed: list[Claim] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.by_key)

    def at_key(self, key: str) -> Claim | None:
        """The live claim under ``key``, or ``None``."""
        return self.by_key.get(key)

    def at_path(self, path: Path, key: str) -> Claim | None:
        """The live claim made for exactly ``path``, or ``None``. ``key`` is the key
        ``path`` was claimed under (``claimed_key``), or its current one."""
        claim = self.by_key.get(key)
        if claim is None or not _same_spelling(claim.path, path):
            return None
        return claim

    def claimed_key(self, path: Path) -> str | None:
        """The key ``path`` was claimed under, if it was."""
        return self._key_of.get(os.fspath(path))

    def is_live(self, claim: Claim) -> bool:
        return self.by_key.get(claim.key) is claim

    def claim(self, path: Path, key: str, physical: Path, index: int) -> Claim:
        """Claim ``path`` under ``key`` for result ``index``. Claiming a key someone
        else holds transfers it: a third member colliding revises the second."""
        claim = Claim(path, index, physical, key)
        self.by_key[key] = claim
        self._key_of[os.fspath(path)] = key
        self._unindexed.append(claim)
        return claim

    def land(
        self,
        path: Path,
        key: str,
        physical: Path,
        index: int,
        *,
        replaced: Claim | None,
    ) -> Claim:
        """Record that result ``index`` landed a file at ``path``, over the file of
        ``replaced`` (its owner before the write, from :meth:`owner`), if any.

        The one place a landing updates ownership: the replaced claim is retired, even
        when it was made under another key (a case variant under TRUSTED, whose key
        does not fold it), so it can never answer for the new file. A replaced claim
        under ``key`` itself is superseded by the new claim."""
        if replaced is not None and replaced.key != key and self.is_live(replaced):
            del self.by_key[replaced.key]
        return self.claim(path, key, physical, index)

    def release(self, path: Path, key: str) -> bool:
        """Drop the claim made for ``path``, under ``key`` (as for :meth:`at_path`),
        once its content is gone. Whether there was one."""
        if self.at_path(path, key) is None:
            return False
        del self.by_key[key]
        return True

    def owner(self, path: Path, key: str, *, occupied: bool) -> Claim | None:
        """The live claim on the entry at ``path`` now, or else the one under ``key``.

        ``occupied`` says whether ``path`` holds an entry; pass ``False`` where only
        the key's answer is needed, which costs no ``lstat``. When it does, the claim
        under ``key`` stands if the entry is its file. Otherwise the filesystem
        decides: the claim whose file is that entry wins, under whatever name it was
        claimed (a case variant on a case-insensitive filesystem, an 8.3 short name, a
        spelling NTFS's upcase table folds and ``casefold`` does not). With no such
        claim, or on a filesystem that reports inode 0, the key decides."""
        if not self.by_key:
            return None
        keyed = self.by_key.get(key)
        if not occupied:
            return keyed
        try:
            st = os.lstat(long_path(path))
        except OSError:
            return keyed
        if st.st_ino == 0:
            return keyed
        if keyed is not None and _is_file_of(keyed, st):
            return keyed
        found = self._by_identity(path, st)
        return found if found is not None else keyed

    def by_identity(self, path: Path) -> Claim | None:
        """The live claim whose file is the entry at ``path``, under whatever name it
        was claimed, or ``None``. ``path`` should hold an entry: this costs an
        ``lstat``, plus one per claim made since the last identity lookup."""
        try:
            st = os.lstat(long_path(path))
        except OSError:
            return None
        return self._by_identity(path, st)

    def _by_identity(self, path: Path, st: os.stat_result) -> Claim | None:
        if st.st_ino == 0:
            return None
        for claim in self._unindexed:
            if not self.is_live(claim):
                continue
            with contextlib.suppress(OSError):
                cst = os.lstat(long_path(claim.path))
                self._by_id.setdefault((cst.st_dev, cst.st_ino), []).append(claim)
        self._unindexed.clear()
        live = [
            claim
            for claim in self._by_id.get((st.st_dev, st.st_ino), ())
            if self.is_live(claim)
        ]
        # Hard links of one file are several entries. The entry here is the claim
        # whose name folds to this one (case, Unicode normalization, a trailing dot
        # or space) in the same directory; a name that test cannot decide (an 8.3
        # short name) takes the latest claim of the file.
        name = _folded(path.name)
        for claim in reversed(live):
            if (
                _folded(claim.path.name) == name
                and _same_directory(claim.path, path)
                and _is_file_of(claim, st)
            ):
                return claim
        for claim in reversed(live):
            if _is_file_of(claim, st):
                return claim
        return None


def _folded(name: str) -> str:
    return collision_key(name, ExtractionPolicy.STANDARD)


def _same_directory(a: Path, b: Path) -> bool:
    """Whether the parents of ``a`` and ``b`` are one directory."""
    try:
        return os.path.samestat(
            os.stat(long_path(a.parent)), os.stat(long_path(b.parent))
        )
    except OSError:
        return False


def _is_file_of(claim: Claim, st: os.stat_result) -> bool:
    """Whether the entry ``st`` describes is the file at ``claim.path`` now."""
    try:
        return os.path.samestat(st, os.lstat(long_path(claim.path)))
    except OSError:
        return False
