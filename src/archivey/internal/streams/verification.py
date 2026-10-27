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
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VerificationProofs:
    """One layer's answer, combined with the answers below it.

    ``key_in_doubt``: a check that can pass by chance accepted the member's password,
    and nothing has confirmed it since. ``ended``: a read reached the end with every
    length and end-of-data check passing. ``content``: a check over every byte
    matched. ``content_possible``: such a check exists, so a read to the end can match
    it. The last three hold for the member's own bytes only.
    """

    key_in_doubt: bool = False
    ended: bool = False
    content: bool = False
    content_possible: bool = False

    def combine(self, below: VerificationProofs) -> VerificationProofs:
        """This layer's proofs together with the ones of the layer below it."""
        return VerificationProofs(
            key_in_doubt=self.key_in_doubt or below.key_in_doubt,
            ended=self.ended or below.ended,
            content=self.content or below.content,
            content_possible=self.content_possible or below.content_possible,
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
