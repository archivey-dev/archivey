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
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from archivey.internal.long_paths import long_path


@dataclass(frozen=True)
class Claim:
    """A destination claimed by a member written this run, with the index of that
    member's result. A later ``REPLACE`` onto the destination revises that result.

    ``physical`` is where the claimed file was when it was claimed, with every parent
    resolved. The key is taken from it, and a collision is routed to it. ``path`` can
    run through a caller's symlink that a later member replaces, so it can stop naming
    that file.
    """

    path: Path
    result_index: int
    physical: Path


@dataclass
class Placements:
    """The live claims of one run, by collision key and by file identity.

    A claim is live while ``by_key`` holds it under the key it was claimed under.
    The identity index is filled lazily: a claim waits in ``_unindexed`` until the
    first identity lookup after it was made, so a run into an empty destination costs
    no ``lstat``. An identity hit is checked again against the claimed path, as an
    inode can be reused once its file is gone.
    """

    by_key: dict[str, Claim] = field(default_factory=dict)
    # The key each claimed path was claimed under, so a release finds the claim after
    # a symlink in its path was replaced and the path resolves somewhere else.
    key_of: dict[Path, str] = field(default_factory=dict)
    _by_id: dict[tuple[int, int], Claim] = field(default_factory=dict)
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
        return claim if claim is not None and claim.path == path else None

    def claimed_key(self, path: Path) -> str | None:
        """The key ``path`` was claimed under, if it was."""
        return self.key_of.get(path)

    def is_live(self, claim: Claim) -> bool:
        key = self.key_of.get(claim.path)
        return key is not None and self.by_key.get(key) is claim

    def claim(self, path: Path, key: str, physical: Path, index: int) -> Claim:
        """Claim ``path`` under ``key`` for result ``index``. Claiming a key someone
        else holds transfers it: a third member colliding revises the second."""
        claim = Claim(path, index, physical)
        self.by_key[key] = claim
        self.key_of[path] = key
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
        does not fold it), so it can never answer for the new file."""
        if replaced is not None and replaced.path != path:
            replaced_key = self.key_of.get(replaced.path)
            if replaced_key is not None:
                self.release(replaced.path, replaced_key)
        return self.claim(path, key, physical, index)

    def release(self, path: Path, key: str) -> bool:
        """Drop the claim made for ``path``, under ``key`` (as for :meth:`at_path`),
        once its content is gone. Whether there was one."""
        claim = self.by_key.get(key)
        if claim is None or claim.path != path:
            return False
        del self.by_key[key]
        return True

    def owner(self, path: Path, key: str, *, occupied: bool) -> Claim | None:
        """The live claim on the entry at ``path`` now, or else the one under ``key``.

        ``occupied`` says whether ``path`` holds an entry. When it does, the
        filesystem decides: the claim whose file is that entry wins, under whatever
        name it was claimed (a case variant on a case-insensitive filesystem, an 8.3
        short name, a spelling NTFS's upcase table folds and ``casefold`` does not).
        A filesystem that reports inode 0 cannot be asked, and the key decides."""
        if not self.by_key:
            return None
        if occupied:
            found = self.by_identity(path)
            if found is not None:
                return found
        return self.by_key.get(key)

    def by_identity(self, path: Path) -> Claim | None:
        """The live claim whose file is the entry at ``path``, under whatever name it
        was claimed, or ``None``. ``path`` should hold an entry: this costs an
        ``lstat``, plus one per claim made since the last identity lookup."""
        try:
            st = os.lstat(long_path(path))
        except OSError:
            return None
        if st.st_ino == 0:
            return None
        for claim in self._unindexed:
            if not self.is_live(claim):
                continue
            with contextlib.suppress(OSError):
                cst = os.lstat(long_path(claim.path))
                self._by_id[cst.st_dev, cst.st_ino] = claim
        self._unindexed.clear()
        claim = self._by_id.get((st.st_dev, st.st_ino))
        if claim is None or not self.is_live(claim):
            return None
        try:
            if not os.path.samestat(st, os.lstat(long_path(claim.path))):
                return None
        except OSError:
            return None
        return claim
