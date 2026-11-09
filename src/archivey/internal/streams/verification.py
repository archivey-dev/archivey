"""What a member stream's layers have proved, for ``ArchiveStream.verified``.

Each check runs in its own layer: the member verifier (length and stored digests), a
codec's own checksum, the WinZip AES HMAC in the decrypt stage, the password watch
over a member whose password only a weak check accepted. The public stream asks the
layer below it with :func:`ask_verification_proofs` and combines the answers into a
:class:`~archivey.types.Verification` level (``verification-level`` change).

A layer answers through a private ``_verification_proofs()`` method, duck-typed as
``_digest_intact()`` is (:func:`~archivey.internal.streams.verify.ask_digest_intact`).
A layer with no such method passes on only the doubt about a key: a slice (a TAR
member's view of the archive's decoded stream) must not pass on a check that covers
the whole archive as its member's, and doubt is always safe to pass on. A
pass-through wrapper that changes no byte positions sets ``forwards_verification``
to pass on everything.
"""

from __future__ import annotations

import io
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from archivey.exceptions import CorruptionError
from archivey.types import Verification

if TYPE_CHECKING:
    from archivey.types import ArchiveMember


@dataclass(frozen=True, slots=True)
class VerificationProofs:
    """One layer's answer, combined with the answers below it.

    ``key_in_doubt``: a check that can pass by chance accepted the member's password,
    and nothing has confirmed it since. ``ended``: a read reached the end with every
    length and end-of-data check passing. ``content``: a check over every byte
    matched. ``content_possible``: such a check exists, so a read to the end can match
    it. The last three come from a codec whose check is optional per frame (xz,
    zstd, LZ4), and the stream above turns them into the other proofs.
    ``per_frame``: the codec is one of these. ``frames_checked``: it has seen at least
    one frame and every frame it has seen carries a check its library verifies, which
    a read from the start to the end turns into a check of every byte.
    ``frame_unchecked``: a frame it has seen carries no such check, so no read can
    check every byte. All but ``key_in_doubt`` hold for the member's own bytes only.
    """

    key_in_doubt: bool = False
    ended: bool = False
    content: bool = False
    content_possible: bool = False
    per_frame: bool = False
    frames_checked: bool = False
    frame_unchecked: bool = False

    def combine(self, below: VerificationProofs) -> VerificationProofs:
        """This layer's proofs together with the ones of the layer below it."""
        return VerificationProofs(
            key_in_doubt=self.key_in_doubt or below.key_in_doubt,
            ended=self.ended or below.ended,
            content=self.content or below.content,
            content_possible=self.content_possible or below.content_possible,
            per_frame=self.per_frame or below.per_frame,
            frames_checked=self.frames_checked or below.frames_checked,
            frame_unchecked=self.frame_unchecked or below.frame_unchecked,
        )

    def doubt_only(self) -> VerificationProofs:
        """Only the doubt about the key, for a layer that changes byte positions."""
        return VerificationProofs(key_in_doubt=self.key_in_doubt)


NO_PROOFS = VerificationProofs()

# A wrapper chain is a handful of layers; the bound only stops a cycle.
MAX_WRAPPER_DEPTH = 64


def ask_verification_proofs(stream: object, *, _depth: int = 0) -> VerificationProofs:
    """Ask ``stream`` what it and the layers below it have proved.

    A layer with a ``_verification_proofs()`` method answers for itself and the layers
    below it. A ``BufferedReader`` passes on its raw stream's answer. Otherwise the
    answer comes from its ``_inner``: whole when the layer sets
    ``forwards_verification``, else only the doubt about a key.
    """
    if stream is None or _depth > MAX_WRAPPER_DEPTH:
        return NO_PROOFS
    ask = getattr(stream, "_verification_proofs", None)
    if ask is not None:
        answer = ask()
        return answer if isinstance(answer, VerificationProofs) else NO_PROOFS
    if isinstance(stream, io.BufferedReader):
        # A read buffer changes no byte (a decoder's input buffer over a decrypt stage).
        return ask_verification_proofs(stream.raw, _depth=_depth + 1)
    inner = getattr(stream, "_inner", None)
    if inner is None:
        return NO_PROOFS
    below = ask_verification_proofs(inner, _depth=_depth + 1)
    if getattr(stream, "forwards_verification", False) is True:
        return below
    return below.doubt_only()


def find_frame_watch(stream: object, *, _depth: int = 0) -> Callable[[], bool] | None:
    """The check of the codec layer whose per-frame proofs reach ``stream``.

    It answers whether that layer has seen a frame with no check
    (``VerificationProofs.frame_unchecked``), without the walk
    :func:`ask_verification_proofs` takes, so a stream can ask after each read. It
    follows the same layers that walk passes ``per_frame`` through, so it finds the
    layer whenever that proof reaches ``stream``; ``None`` when there is none.
    """
    if stream is None or _depth > MAX_WRAPPER_DEPTH:
        return None
    watch = getattr(stream, "_frames_unchecked_now", None)
    if watch is not None:
        return watch
    if isinstance(stream, io.BufferedReader):
        return find_frame_watch(stream.raw, _depth=_depth + 1)
    inner = getattr(stream, "_inner", None)
    if inner is None:
        return None
    if (
        getattr(stream, "_verification_proofs", None) is not None
        or getattr(stream, "forwards_verification", False) is True
    ):
        return find_frame_watch(inner, _depth=_depth + 1)
    return None


# The level lock (``verification-level-redesign`` design Decision 4): a leaf lock held
# only for the compare-and-store below, never across I/O or a callback, and no other
# lock is taken while it is held. One for the process: the critical section is a few
# attribute reads and writes, so sharing it costs nothing measurable.
_LEVEL_LOCK = threading.Lock()


def raise_member_level(
    member: ArchiveMember,
    verified: Verification,
    verifiable: Verification | None,
    *,
    without_frames: Verification | None = None,
) -> None:
    """Raise ``member``'s level to what a stream of it has proved.

    ``verified`` only rises. ``verifiable`` is the stream's ceiling once it has opened
    its data (``None`` before): the first one settles the member's, which can lower
    the listing's estimate, and later ones only raise it.

    ``without_frames`` is that ceiling without a codec's per-frame checks, for a stream
    whose ceiling counts them. It replaces ``verifiable`` once any read of the member
    has found a frame with no check (``ArchiveMember._frame_unchecked``). The flag is
    read here, under the lock, so a stream that computed its ceiling before another
    stream found such a frame does not raise the member back.

    A member a check over several members covers (``ArchiveMember._spanning_checksum``)
    keeps ``CHECKSUM`` as its ceiling whatever its own stream can reach: that check
    proves every byte, and the key with them, once it passes. The flag is read here,
    under the lock, so a stream does not raise the ceiling back after
    :func:`drop_spanning_ceiling` cleared it.
    """
    with _LEVEL_LOCK:
        member._verified = max(member._verified, verified)
        if without_frames is not None and member._frame_unchecked:
            verifiable = without_frames
        # ``verifiable`` is None while the stream has not opened its data: it has no
        # ceiling to report, and the member keeps the listing's estimate (which
        # already counts the spanning flag). Once it reports one, a member that a
        # check over several members covers keeps CHECKSUM, though its own stream
        # can only reach LENGTH.
        if verifiable is not None and member._spanning_checksum:
            verifiable = Verification.CHECKSUM
        if verifiable is not None:
            settled = member._verifiable
            if settled is None or verifiable > settled:
                member._verifiable = verifiable


class SpanningCheckError(CorruptionError):
    """A check over the data of several members failed (a 7z folder CRC).

    Raised by the read that reaches the end of the data the check covers. ``covers``
    holds the reader's own members whose bytes only that check proves; ``verify_all()``
    returns each of them as a failure with this error, whichever member's read raised
    it. Internal: callers see a :class:`CorruptionError`.
    """

    def __init__(self, message: str, *, covers: tuple[ArchiveMember, ...]) -> None:
        super().__init__(message)
        self.covers = covers


def note_frame_unchecked(member: ArchiveMember, ceiling: Verification) -> None:
    """Record that a read of ``member`` found a frame with no check, and lower its
    ``verifiable`` from ``CHECKSUM`` to ``ceiling``.

    The codec's per-frame checks cannot check every byte then, and ``ceiling`` is what
    the other layers can still reach. ``ArchiveMember._frame_unchecked`` keeps it for
    every later stream of the member, which may see only checked frames.
    """
    with _LEVEL_LOCK:
        member._frame_unchecked = True
        if member._verifiable is Verification.CHECKSUM:
            member._verifiable = ceiling


def mark_spanning_checksum(member: ArchiveMember) -> None:
    """Record that a check over several members covers ``member``'s bytes.

    Its ``verifiable`` is ``CHECKSUM`` from then on, until the check passes (which
    raises ``verified`` there too) or :func:`drop_spanning_ceiling` finds a frame
    with no check.
    """
    with _LEVEL_LOCK:
        member._spanning_checksum = True
        # Unsettled (None): the listing's estimate reads the flag, nothing to store.
        # Settled: only if a stream opened the member before it was marked, which no
        # reader does today (they mark while listing); kept so the order cannot matter.
        if member._verifiable is not None:
            member._verifiable = Verification.CHECKSUM


def drop_spanning_ceiling(member: ArchiveMember, ceiling: Verification) -> None:
    """Record that the check over several members covering ``member`` cannot cover
    every byte, because a walk found a frame of it with no check.

    That is the format, not damage: damage leaves the ceiling where it is and makes
    the member a failure of ``verify_all()`` instead
    (``BaseArchiveReader._note_spanning_unreachable``). The member's ``verifiable``
    falls once, to ``ceiling``, what its own read can reach, and no stream raises it
    back. A member the check already raised keeps its level.
    """
    with _LEVEL_LOCK:
        if not member._spanning_checksum:
            return  # never covered, or dropped already: falls at most once
        # Cleared first, so no stream raises the ceiling back (raise_member_level).
        member._spanning_checksum = False
        if member._verified is Verification.CHECKSUM:
            return  # its own checks, or the spanning one earlier, proved it all
        # Stored even when unsettled, so the listing's estimate stops counting it.
        member._verifiable = ceiling
