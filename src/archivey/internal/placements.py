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

import os
from dataclasses import dataclass, field
from pathlib import Path

from archivey.internal.filters import collision_key
from archivey.internal.long_paths import long_path
from archivey.types import ExtractionPolicy

_FileId = tuple[int, int]
_FoldedEntryKey = tuple[str, int, int]


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
    once its file is gone.

    One inode can hold several claims, because an archive's hard link gives its file
    a second directory entry. The index keeps them by entry (the folded name and the
    directory it is in), so a lookup costs the same however many links there are, and
    a claim leaves the index when it is retired.
    """

    by_key: dict[str, Claim] = field(default_factory=dict)
    # The key each claimed path was claimed under, by spelling, so a release finds the
    # claim after a symlink in its path was replaced and the path resolves elsewhere.
    _key_of: dict[str, str] = field(default_factory=dict)
    # (st_dev, st_ino) -> entry (folded name, parent st_dev, parent st_ino) -> claim.
    # Names that fold to one entry key can still be distinct entries (``A`` beside
    # ``a`` on a case-sensitive filesystem), so each entry key holds its claims by
    # exact spelling.
    _by_id: dict[_FileId, dict[_FoldedEntryKey, dict[str, Claim]]] = field(
        default_factory=dict
    )
    # Where each indexed claim sits in ``_by_id``, by ``id``, so retiring it is cheap.
    _slot: dict[int, tuple[_FileId, _FoldedEntryKey, str]] = field(default_factory=dict)
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
        superseded = self.by_key.get(key)
        if superseded is not None:
            self._unindex(superseded)
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

        The replaced claim is retired, even when it was made under another key (a
        case variant under TRUSTED, whose key does not fold it), so it can never
        answer for the new file. A replaced claim under ``key`` itself is superseded
        by the new claim."""
        if replaced is not None and replaced.key != key:
            self.retire(replaced)
        return self.claim(path, key, physical, index)

    def retire(self, claim: Claim) -> bool:
        """Drop ``claim`` once its file is gone (replaced, or removed by a write that
        then failed), under whatever key it was made. Whether it was live."""
        if not self.is_live(claim):
            return False
        del self.by_key[claim.key]
        self._unindex(claim)
        return True

    def _unindex(self, claim: Claim) -> None:
        slot = self._slot.pop(id(claim), None)
        if slot is None:
            return
        file_id, entry, spelling = slot
        entries = self._by_id[file_id]
        spellings = entries[entry]
        del spellings[spelling]
        if not spellings:
            del entries[entry]
        if not entries:
            del self._by_id[file_id]

    def release(self, path: Path, key: str) -> bool:
        """Drop the claim made for ``path``, under ``key`` (as for :meth:`at_path`),
        once its content is gone. Whether there was one."""
        claim = self.at_path(path, key)
        return claim is not None and self.retire(claim)

    def owner(self, path: Path, key: str, *, occupied: bool) -> Claim | None:
        """The live claim on the entry at ``path`` now, or else the one under ``key``.

        ``occupied`` says whether ``path`` holds an entry; pass ``False`` where only
        the key's answer is needed, which costs no ``lstat``. When it does, the claim
        under ``key`` stands if the entry is its file. Otherwise the filesystem
        decides: the claim whose file is that entry wins, under whatever name it was
        claimed (a case variant on a case-insensitive filesystem, an 8.3 short name, a
        spelling NTFS's upcase table folds and ``casefold`` does not). With no such
        claim, or none that names this entry rather than another hard link of its
        file, or on a filesystem that reports inode 0, the key decides."""
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
        found = self._entry_owner(path, st)
        return found if found is not None else keyed

    def by_identity(self, path: Path) -> Claim | None:
        """A live claim whose file is the entry at ``path``, under whatever name it
        was claimed, or ``None``: the one naming this entry when the file has several
        hard links and one can be told. ``path`` should hold an entry: this costs an
        ``lstat``, plus one per claim made since the last identity lookup."""
        try:
            st = os.lstat(long_path(path))
        except OSError:
            return None
        if st.st_ino == 0:
            return None
        found = self._entry_owner(path, st)
        if found is not None:
            return found
        for spellings in self._by_id.get((st.st_dev, st.st_ino), {}).values():
            for claim in spellings.values():
                if self.is_live(claim) and _is_file_of(claim, st):
                    return claim
        return None

    def _entry_owner(self, path: Path, st: os.stat_result) -> Claim | None:
        """The live claim on the directory entry at ``path``, which ``st`` describes:
        the claim of its file made in the same directory under a name that folds to
        this one (case, Unicode normalization, a trailing dot or space), the one
        spelled exactly so where several are, or else the file's only claim when the
        file has one directory entry. A file with several entries and no such name (an
        8.3 short name of one of its hard links, claimed or not) has no answer here:
        its file cannot tell which entry the name reaches, and a wrong answer would
        send a write to another one."""
        if st.st_ino == 0:
            return None
        self._index_new_claims()
        file_id = (st.st_dev, st.st_ino)
        entries = self._by_id.get(file_id)
        if not entries:
            return None
        parent = _dir_id(path)
        if parent is not None:
            spellings = entries.get((_folded(path.name), *parent))
            if spellings:
                claim = spellings.get(path.name)
                if claim is None and len(spellings) == 1:
                    (claim,) = spellings.values()
                if claim is not None and self.is_live(claim) and _is_file_of(claim, st):
                    return claim
        # The file's only claim: one folded entry key, spelled one way, on a file with
        # one directory entry. A file with more (an unclaimed hard link, such as a
        # copy taken back from a name that folds to this one) cannot tell which entry
        # the name reaches, and the claim of another entry would take the write.
        if len(entries) == 1 and _entry_count(st) == 1:
            (spellings,) = entries.values()
            if len(spellings) == 1:
                (claim,) = spellings.values()
                if self.is_live(claim) and _is_file_of(claim, st):
                    return claim
        return None

    def _index_new_claims(self) -> None:
        for claim in self._unindexed:
            if not self.is_live(claim):
                continue
            parent = _dir_id(claim.path)
            if parent is None:
                continue
            try:
                cst = os.lstat(long_path(claim.path))
            except OSError:
                continue
            file_id = (cst.st_dev, cst.st_ino)
            entry = (_folded(claim.path.name), *parent)
            spellings = self._by_id.setdefault(file_id, {}).setdefault(entry, {})
            earlier = spellings.get(claim.path.name)
            if earlier is not None:
                self._unindex(earlier)
                spellings = self._by_id.setdefault(file_id, {}).setdefault(entry, {})
            spellings[claim.path.name] = claim
            self._slot[id(claim)] = (file_id, entry, claim.path.name)
        self._unindexed.clear()


def _folded(name: str) -> str:
    return collision_key(name, ExtractionPolicy.STANDARD)


def _dir_id(path: Path) -> tuple[int, int] | None:
    """The identity of the directory ``path`` is in, following symlinks."""
    try:
        st = os.stat(long_path(path.parent))
    except OSError:
        return None
    return st.st_dev, st.st_ino


def _entry_count(st: os.stat_result) -> int:
    """How many directory entries the file ``st`` describes has (its link count)."""
    return st.st_nlink


def _is_file_of(claim: Claim, st: os.stat_result) -> bool:
    """Whether the entry ``st`` describes is the file at ``claim.path`` now."""
    try:
        return os.path.samestat(st, os.lstat(long_path(claim.path)))
    except OSError:
        return False
