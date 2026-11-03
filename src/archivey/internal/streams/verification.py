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
from dataclasses import dataclass
from typing import TYPE_CHECKING

from archivey.exceptions import CorruptionError

if TYPE_CHECKING:
    from archivey.types import ArchiveMember, Verification


@dataclass(frozen=True, slots=True)
class VerificationProofs:
    """One layer's answer, combined with the answers below it.

    ``key_in_doubt``: a check that can pass by chance accepted the member's password,
    and nothing has confirmed it since. ``ended``: a read reached the end with every
    length and end-of-data check passing. ``content``: a check over every byte
    matched. ``content_possible``: such a check exists, so a read to the end can match
    it. ``frames_checked``: a codec whose check is optional per frame (xz, zstd, LZ4)
    has seen at least one frame and every frame it has seen carries a check its
    library verifies; the stream above counts it as a codec that checks every byte,
    which a read from the start to the end proves. All but ``key_in_doubt`` hold for
    the member's own bytes only.
    """

    key_in_doubt: bool = False
    ended: bool = False
    content: bool = False
    content_possible: bool = False
    frames_checked: bool = False

    def combine(self, below: VerificationProofs) -> VerificationProofs:
        """This layer's proofs together with the ones of the layer below it."""
        return VerificationProofs(
            key_in_doubt=self.key_in_doubt or below.key_in_doubt,
            ended=self.ended or below.ended,
            content=self.content or below.content,
            content_possible=self.content_possible or below.content_possible,
            frames_checked=self.frames_checked or below.frames_checked,
        )

    def doubt_only(self) -> VerificationProofs:
        """Only the doubt about the key, for a layer that changes byte positions."""
        return VerificationProofs(key_in_doubt=self.key_in_doubt)


NO_PROOFS = VerificationProofs()

# A wrapper chain is a handful of layers; the bound only stops a cycle.
_MAX_DEPTH = 64


def ask_verification_proofs(stream: object, *, _depth: int = 0) -> VerificationProofs:
    """Ask ``stream`` what it and the layers below it have proved.

    A layer with a ``_verification_proofs()`` method answers for itself and the layers
    below it. A ``BufferedReader`` passes on its raw stream's answer. Otherwise the
    answer comes from its ``_inner``: whole when the layer sets
    ``forwards_verification``, else only the doubt about a key.
    """
    if stream is None or _depth > _MAX_DEPTH:
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


# The level lock (``verification-level-redesign`` design Decision 4): a leaf lock held
# only for the compare-and-store below, never across I/O or a callback, and no other
# lock is taken while it is held. One for the process: the critical section is a few
# attribute reads and writes, so sharing it costs nothing measurable.
_LEVEL_LOCK = threading.Lock()


def raise_member_level(
    member: ArchiveMember,
    verified: Verification,
    verifiable: Verification | None,
) -> None:
    """Raise ``member``'s level to what a stream of it has proved.

    ``verified`` only rises. ``verifiable`` is the stream's ceiling once it has opened
    its data (``None`` before): the first one settles the member's, which can lower
    the listing's estimate, and later ones only raise it.
    """
    with _LEVEL_LOCK:
        member._verified = max(member._verified, verified)
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


def note_ceiling_provisional(member: ArchiveMember, provisional: bool) -> None:
    """Record whether ``member``'s per-frame checks still wait on a read from the start.

    ``False`` settles it for good: a read from the start has ended, so its answer is
    the member's ``verifiable``. ``True`` holds only until then
    (``ArchiveMember._ceiling_provisional``).
    """
    with _LEVEL_LOCK:
        if member._ceiling_provisional is not False:
            member._ceiling_provisional = provisional
