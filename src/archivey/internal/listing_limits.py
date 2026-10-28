"""Retained metadata-byte accounting for :class:`~archivey.config.ListingLimits`."""

from __future__ import annotations

from collections.abc import Mapping

from archivey.config import ListingLimits
from archivey.exceptions import ResourceLimitError
from archivey.internal.lazy_fields import extra_is_unbuilt
from archivey.types import ArchiveMember


def _str_retained_bytes(value: str) -> int:
    """Cheap upper bound on UTF-8 size for listing bomb accounting.

    ``max_metadata_bytes`` is a safety cap, not a precise allocator — encoding
    every field on the open+list hot path is wasted work. UTF-8 is at most 4
    bytes per Unicode code point, so ``4 * len(s)`` never under-counts a
    Unicode name bomb; ASCII uses ``len(s)`` (exact, the common case).
    """
    n = len(value)
    return n if value.isascii() else n * 4


def _retained_bytes(value: object) -> int:
    """Retained size of a ``str``/``bytes`` value; anything else weighs nothing."""
    if isinstance(value, str):
        return _str_retained_bytes(value)
    if isinstance(value, bytes):
        return len(value)
    return 0


def text_bytes(value: str | bytes | None) -> int:
    """Retained weight of one stored text field, by the rule :class:`ListingLimitTracker`
    uses for member fields: ``bytes`` by length, ``str`` per :func:`_str_retained_bytes`.

    For a parser that weighs what it keeps before members are registered (7z, RAR).
    """
    return _retained_bytes(value)


# What one entry of a nested dict keyed by a number retains beyond its value's bytes:
# the key object, the dict slot and the value's object header. Measured 69 bytes for
# a ZIP extra field with one byte of data (CPython 3.11, int key over 256).
NUMBERED_ENTRY_BYTES = 72


def _extra_bytes(extra: Mapping[str, object]) -> int:
    """Sum retained ``str``/``bytes`` lengths in ``extra`` (one-level nested dicts).

    Values count at both levels; keys count only inside a nested dict. A top-level
    key is a format-defined literal (``zip.compress_type``, ``tar.type``) that no
    archive sizes, so charging it would only tighten the cap by a per-format toll.
    A nested key is archive text: TAR copies every PAX record into
    ``extra["tar.pax_headers"]``, where the keyword is as attacker-sized as the value.
    A nested key that is not text (a ZIP extra field's tag in
    ``extra["zip.extra_fields"]``) weighs ``NUMBERED_ENTRY_BYTES``: the archive sets
    how many entries there are, and an empty value would otherwise weigh nothing.
    """
    total = 0
    for value in extra.values():
        if type(value) is int:
            # The common value (``zip.compress_type``, ``tar.type``): weighs nothing.
            continue
        if isinstance(value, dict):
            for nested_key, nested in value.items():
                key_bytes = (
                    _retained_bytes(nested_key)
                    if isinstance(nested_key, (str, bytes))
                    else NUMBERED_ENTRY_BYTES
                )
                total += key_bytes + _retained_bytes(nested)
        else:
            total += _retained_bytes(value)
    return total


def member_metadata_bytes(member: ArchiveMember) -> int:
    """Retained metadata weight for one member (listing bomb accounting)."""
    # Hot path for every listing: most optional string fields are None, and the
    # ``_str_retained_bytes`` rule is inlined for the name.
    name = member.name
    total = len(name) if name.isascii() else len(name) * 4
    raw_name = member.raw_name
    if raw_name is not None:
        total += len(raw_name)
    comment = member.comment
    if comment is not None:
        total += _str_retained_bytes(comment)
    link_target = member.link_target
    if link_target is not None:
        total += _str_retained_bytes(link_target)
    uname = member.uname
    if uname is not None:
        total += _str_retained_bytes(uname)
    gname = member.gname
    if gname is not None:
        total += _str_retained_bytes(gname)
    # An unbuilt bag holds only its format's ``int`` key, which weighs nothing; reading
    # it here would build it for every listed member.
    if not extra_is_unbuilt(member):
        extra = member.extra
        if extra:
            total += _extra_bytes(extra)
    return total


def archive_comment_bytes(comment: str | None) -> int:
    if comment is None:
        return 0
    return _str_retained_bytes(comment)


class ListingLimitTracker:
    """Accumulate member count + retained metadata; optionally raise when caps are crossed."""

    def __init__(self, limits: ListingLimits) -> None:
        self._limits = limits
        self.member_count = 0
        self.metadata_bytes = 0
        self._archive_comment_counted = False

    def reset(self) -> None:
        self.member_count = 0
        self.metadata_bytes = 0
        self._archive_comment_counted = False

    def account_archive_comment(
        self, comment: str | None, *, enforce: bool = True
    ) -> None:
        if self._archive_comment_counted:
            return
        self._archive_comment_counted = True
        added = archive_comment_bytes(comment)
        if added <= 0:
            return
        self._add_bytes(added, enforce=enforce)

    def account_member(self, member: ArchiveMember, *, enforce: bool = True) -> None:
        # Called once per member of every listing, so the checks are inlined; each
        # raise still goes through the shared helpers.
        next_count = self.member_count + 1
        next_bytes = self.metadata_bytes + member_metadata_bytes(member)
        if enforce:
            limits = self._limits
            max_members = limits.max_members
            if max_members is not None and next_count > max_members:
                self._check_members(next_count)
            max_meta = limits.max_metadata_bytes
            if max_meta is not None and next_bytes > max_meta:
                self._check_metadata(next_bytes)
        # Raises before storing, so a refused member changes neither total.
        self.metadata_bytes = next_bytes
        self.member_count = next_count

    def account_link_target(self, target: str, *, enforce: bool = True) -> None:
        """Add a link target that was resolved after its member was registered.

        ZIP, 7z and RAR4 keep a symlink's target in the member's data, which is read
        only once every member is registered, so :meth:`account_member` saw ``None``
        for it. Weighing it here is what makes ``max_metadata_bytes`` hold for the
        ``link_target`` field the spec names.
        """
        self._add_bytes(_str_retained_bytes(target), enforce=enforce)

    def account_retained_bytes(self, nbytes: int, *, enforce: bool = True) -> None:
        """Add metadata a backend retains for a member outside its public fields.

        TAR keeps a sparse member's map on the ``TarInfo`` it reads the data through,
        where :func:`member_metadata_bytes` cannot see it.
        """
        self._add_bytes(nbytes, enforce=enforce)

    def _add_bytes(self, nbytes: int, *, enforce: bool) -> None:
        next_bytes = self.metadata_bytes + nbytes
        if enforce:
            self._check_metadata(next_bytes)
        self.metadata_bytes = next_bytes

    def assert_within_limits(self) -> None:
        """Re-check accumulated totals (e.g. when returning a previously built cache)."""
        self._check_members(self.member_count)
        self._check_metadata(self.metadata_bytes)

    def _check_members(self, count: int) -> None:
        max_members = self._limits.max_members
        if max_members is not None and count > max_members:
            raise ResourceLimitError(
                f"Listing limit reached: max_members={max_members} "
                f"(registered {count} members)"
            )

    def _check_metadata(self, nbytes: int) -> None:
        check_metadata_budget(self._limits, nbytes, detail=f"retained {nbytes} bytes")


def check_metadata_budget(limits: ListingLimits, nbytes: int, *, detail: str) -> None:
    """Raise :class:`ResourceLimitError` if ``nbytes`` exceeds ``max_metadata_bytes``.

    ``None`` disables the check. ``detail`` names what was weighed; it goes in the
    parentheses after the limit, so every refusal of this limit reads the same way.
    """
    check_metadata_bytes(limits.max_metadata_bytes, nbytes, detail=detail)


def check_metadata_bytes(max_meta: int | None, nbytes: int, *, detail: str) -> None:
    """Same check, for a caller that holds the ``max_metadata_bytes`` value rather
    than a ``ListingLimits``."""
    if max_meta is not None and nbytes > max_meta:
        raise metadata_limit_error(max_meta, detail)


def metadata_limit_error(max_meta: int, detail: str) -> ResourceLimitError:
    """The refusal of ``max_metadata_bytes``, for a caller on a hot path that compares
    itself and builds ``detail`` only once the limit is crossed."""
    return ResourceLimitError(
        f"Listing limit reached: max_metadata_bytes={max_meta} ({detail})"
    )
