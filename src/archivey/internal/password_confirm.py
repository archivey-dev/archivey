"""Format-agnostic password confirmation, the ladder shared by the ZIP, 7z and RAR
readers.

A format whose password check can admit a wrong value needs a second opinion before it
accepts a candidate. This module supplies that opinion without knowing any format type.
The ladder has three rungs, strongest first:

1. **Cheap key check** — an O(1) test on the key, before any payload is decoded. ZIP
   has two (ZipCrypto's header check byte, WinZip AES's ``pw_verify``); both are weaker
   than 2⁻³², so they eliminate but never confirm. 7z has none in the format. The
   backends apply this rung themselves; it is named here so the ladder reads the same
   in every backend.
2. **Integrity anchor** — a stored CRC over a decodable prefix of the unit.
   :func:`plan_password_confirm` picks the earliest one that verifies at least 4 bytes.
3. **Codec rejection** — a decompressor measured to fail on random input settles a
   wrong key inside a bounded prefix. Surviving that prefix is ``INCONCLUSIVE``, not
   ``CONFIRMED``.

Confirmation is a *rejection filter*, not a proof. The caller's own stream still runs
the authoritative digest at EOF. The candidate loop stays
:meth:`~archivey.internal.password._PasswordCandidates.attempt`;
:func:`attempt_with_confirm` gives it the rule for several candidates:

- A ``CONFIRMED`` candidate wins at once, so an expensive key derivation runs for no
  candidate after it.
- A ``REJECTED`` one is skipped.
- An ``INCONCLUSIVE`` one does not win outright. Every remaining candidate is probed
  as well. A lone survivor wins; when several survive, each in order runs a full check
  that walks to the unit's end anchor, until one is ``CONFIRMED``.

Each format supplies the two checks: a bounded probe and the full check.
"""

from __future__ import annotations

import io
import zlib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import BinaryIO, TypeVar

from archivey.internal.password import _PasswordCandidates
from archivey.internal.streams.codecs import Codec
from archivey.internal.streams.resume import ask_resume_offset
from archivey.internal.streams.streamtools.base import DelegatingStream
from archivey.internal.streams.verification import (
    VerificationProofs,
    ask_verification_proofs,
)
from archivey.internal.streams.verify import ask_digest_intact
from archivey.types import ArchiveMember

# Codecs measured to fail on random input, which is what a wrong key decrypts to
# (``tests/test_password_confirm.py`` re-measures every one). A unit where one of them
# decodes the decrypted bytes settles a wrong key inside the confirm prefix: this is
# ``codec_rejects`` for the 7z and ZIP readers (RAR sets it from its own compression
# method field instead). One that decodes *before* the decryption (a 7z folder can
# store that order) sees the same bytes whatever the key, so it does not count.
# Measured as non-rejecting and left out: Brotli (about one random input in twenty
# decodes a full prefix) and PPMd (about one in a hundred; archivey decodes it in a
# child process, where pyppmd's crash on random input costs the candidate only, see
# ``ProcessIsolation``). Filters never reject. A codec not
# listed is non-rejecting.
REJECTING_CODECS = frozenset(
    {
        Codec.LZMA,
        Codec.LZMA2,
        Codec.BZIP2,
        Codec.DEFLATE,
        Codec.DEFLATE64,
        Codec.ZSTD,
        Codec.LZ4,
    }
)

# Decompressed plaintext budget for confirmation. The codecs in REJECTING_CODECS reject
# wrong-key garbage within a few bytes (the archived bounded-password-confirmation
# design, §2); 64 KiB leaves a wide margin, so a decoder change of a few bytes does not
# flip a verdict, and covers typical members exactly (EOF → CRC).
PASSWORD_CONFIRM_PREFIX_BYTES = 64 * 1024

# Upper bound on the compressed input a bounded confirm may consume to produce its
# plaintext prefix. An output-only bound does not constrain a block-transform codec: 64
# KiB of bzip2 output costs ~905 KB of input on incompressible data, because bzip2 emits
# nothing until it has read a whole block. The number is the inner-TAR probe's
# (``detection._INNER_TAR_MAX_PROBE_BYTES``), sized for the same worst-case bzip2 block;
# a test pins the two equal. The probes do not share a helper: detection decodes through
# a non-consuming peek callable under a detection budget ledger and ends in a ``ustar``
# check, confirmation decodes a borrowed pack view through a decrypting pipeline. The
# number is the part they share.
PASSWORD_CONFIRM_MAX_INPUT_BYTES = 1 << 20

# How many bytes a CRC must cover before a match confirms a password: a CRC over
# fewer carries less than 32 bits of evidence, so it can reject a candidate but never
# confirm one.
PASSWORD_CONFIRM_MIN_VERIFIED_BYTES = 4

# Read size for the confirm walk. Peak extra memory is one chunk, whatever the unit size.
PASSWORD_CONFIRM_CHUNK_BYTES = 64 * 1024

_T = TypeVar("_T")


class PasswordConfirmVerdict(Enum):
    """What one confirmation probe concluded about one candidate."""

    #: The candidate is wrong: an anchor mismatched, the decoder objected, or the
    #: stream ended short. Try the next one.
    REJECTED = "rejected"
    #: A CRC over at least 4 decoded bytes matched (a signal of at least 2⁻³²).
    CONFIRMED = "confirmed"
    #: The candidate survived its budget without reaching a deciding signal.
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class PasswordConfirmPlan:
    """What :func:`run_password_confirm_plan` reads, and what it may conclude.

    ``segments`` are consecutive ``(length, crc)`` runs from the unit's start; a
    ``None`` CRC is read and not checked. ``unit_crc``, when set, is checked over every
    byte the segments cover, which the planner only allows when they cover the whole
    unit. ``confirms`` says whether reading every segment without a mismatch reaches
    ``CONFIRMED``; otherwise the verdict is ``INCONCLUSIVE``. ``bounded`` says the plan
    stops within the plaintext budget, so the caller should also cap the compressed
    input (:data:`PASSWORD_CONFIRM_MAX_INPUT_BYTES`); an unbounded plan walks to a late anchor
    on purpose and takes no input cap.
    """

    segments: tuple[tuple[int, int | None], ...]
    unit_crc: int | None
    confirms: bool
    bounded: bool

    @property
    def read_bytes(self) -> int:
        return sum(length for length, _ in self.segments)


def plan_password_confirm(
    substreams: Iterable[tuple[int, int | None]],
    tail_crc: int | None,
    *,
    budget: int,
    codec_rejects: bool,
    min_verified_bytes: int = PASSWORD_CONFIRM_MIN_VERIFIED_BYTES,
) -> PasswordConfirmPlan:
    """Plan the cheapest decode that can judge one candidate password.

    The plan says how many decoded bytes of the unit (a 7z folder, a ZIP member) to
    read and which stored CRCs to check on the way, so that a wrong password is caught
    as early as possible.

    ``substreams`` are the unit's items in data order, as ``(size, crc | None)``: for
    a 7z folder, its members; for a ZIP member, the member itself. ``tail_crc`` is a
    CRC over the whole unit, when the format stores one (the 7z folder digest).
    ``budget`` is the most decoded bytes worth spending when a check is not in reach
    (:data:`PASSWORD_CONFIRM_PREFIX_BYTES` in both readers). ``codec_rejects`` says the
    unit's decoder chain was measured to fail on the random output a wrong key
    decrypts to, so decoding ``budget`` bytes without an error is already evidence.
    ``min_verified_bytes`` is how many bytes a CRC must cover before a match confirms
    the password: fewer carry less than 32 bits of evidence. The rules:

    - **Earliest sufficient anchor.** Item CRCs are consulted in order, and the plan
      stops once CRC-verified bytes reach ``min_verified_bytes``. ``tail_crc`` sits at
      the unit's end, so it is only ever the last anchor; an item CRC that suffices
      earlier wins.
    - **Anchor inside the budget:** decode to it and stop.
    - **Anchor past the budget:** a chain whose codec rejects random input
      (``codec_rejects``) stops at ``budget`` bytes, since the decoder settles a wrong
      key inside that prefix. A chain that does not reject walks to the anchor:
      nothing else can tell a wrong key from a right one.
    - **No sufficient anchor at all:** decode ``budget`` bytes (or the whole unit, if
      smaller) and stop. Nobody runs an unbounded decode to discover that nothing
      can be checked.

    Anchors met on the way that verify fewer than ``min_verified_bytes`` still reject
    on a mismatch; they just cannot confirm.
    """
    items = list(substreams)
    total = sum(size for size, _ in items)

    segments: list[tuple[int, int | None]] = []
    offset = 0
    verified = 0
    for size, crc in items:
        end = offset + size
        if crc is not None and end > budget and codec_rejects:
            # The next anchor lies past the budget and the decoder decides a wrong key
            # sooner: stop at the budget.
            return _budget_prefix(segments, min(budget, total))
        segments.append((size, crc))
        offset = end
        if crc is not None:
            verified += size
            if verified >= min_verified_bytes:
                return PasswordConfirmPlan(
                    tuple(segments), None, confirms=True, bounded=offset <= budget
                )

    # No item anchor sufficed. A unit CRC is the last anchor there is.
    if tail_crc is not None and (total <= budget or not codec_rejects):
        return PasswordConfirmPlan(
            tuple(segments),
            tail_crc,
            confirms=total >= min_verified_bytes,
            bounded=total <= budget,
        )
    # No sufficient anchor within reach: at most the budget. Nobody runs an unbounded
    # decode to discover that nothing can be checked.
    return _budget_prefix(segments, min(budget, total))


def _budget_prefix(
    segments: list[tuple[int, int | None]], limit: int
) -> PasswordConfirmPlan:
    """A plan that reads exactly ``limit`` bytes, starting from ``segments``.

    The walk in :func:`plan_password_confirm` appends a CRC-less item without looking
    at the budget, so ``segments`` can run past ``limit`` (one large CRC-less member)
    or stop short of it (the next item is the anchor that was cut off). Whole segments
    that end within ``limit`` keep their CRCs, since a short anchor inside the prefix
    can still reject. The rest of the prefix is read unchecked: a CRC over part of an
    item cannot be checked.
    """
    planned: list[tuple[int, int | None]] = []
    offset = 0
    for size, crc in segments:
        if offset + size > limit:
            break
        planned.append((size, crc))
        offset += size
    if offset < limit:
        planned.append((limit - offset, None))
    return PasswordConfirmPlan(tuple(planned), None, confirms=False, bounded=True)


def run_password_confirm_plan(
    stream: BinaryIO,
    plan: PasswordConfirmPlan,
    *,
    chunk_size: int = PASSWORD_CONFIRM_CHUNK_BYTES,
    input_exhausted: Callable[[], bool] | None = None,
) -> PasswordConfirmVerdict:
    """Read ``stream`` as ``plan`` says and return the verdict.

    Reads in chunks of at most ``chunk_size``, so peak extra memory is one chunk. A
    short read is ``REJECTED``: the stream is the decoded unit, and a correct key
    decodes the declared length. The one exception is a short read while
    ``input_exhausted()`` is true: the caller's input cap ended the stream, not the
    key, so it is ``INCONCLUSIVE``. A mismatched anchor is ``REJECTED`` however much
    input it took to produce. Decoder exceptions propagate; the caller decides which of
    them mean "wrong key".
    """
    unit_crc = 0
    for length, expected in plan.segments:
        crc = 0
        remaining = length
        # `> 0`, not truthiness: a stream that over-returns would drive `remaining`
        # negative, and `read(negative)` is read-everything.
        while remaining > 0:
            chunk = stream.read(min(chunk_size, remaining))
            if not chunk:
                if input_exhausted is not None and input_exhausted():
                    return PasswordConfirmVerdict.INCONCLUSIVE
                return PasswordConfirmVerdict.REJECTED
            crc = zlib.crc32(chunk, crc)
            if plan.unit_crc is not None:
                unit_crc = zlib.crc32(chunk, unit_crc)
            remaining -= len(chunk)
        if expected is not None and crc & 0xFFFFFFFF != expected & 0xFFFFFFFF:
            return PasswordConfirmVerdict.REJECTED
    if plan.unit_crc is not None and unit_crc != plan.unit_crc & 0xFFFFFFFF:
        return PasswordConfirmVerdict.REJECTED
    return (
        PasswordConfirmVerdict.CONFIRMED
        if plan.confirms
        else PasswordConfirmVerdict.INCONCLUSIVE
    )


def attempt_with_confirm(
    passwords: _PasswordCandidates,
    member: ArchiveMember | None,
    probe: Callable[[bytes], tuple[_T, PasswordConfirmVerdict]],
    full_check: Callable[[bytes], tuple[_T, PasswordConfirmVerdict]] | None,
) -> tuple[_T, PasswordConfirmVerdict]:
    """Pick a password for one unit from ``passwords`` by confirmation.

    ``probe`` judges one candidate with a bounded check and ``full_check`` with one
    that walks to the unit's end anchor. Both return their result with a verdict that
    is never ``REJECTED``: a rejected candidate raises the wrong-password
    ``EncryptionError`` instead, so the loop moves on. ``full_check`` is ``None`` when
    the probe is already the full check.

    A ``CONFIRMED`` candidate wins at once. ``INCONCLUSIVE`` candidates are gathered
    and settled as :meth:`~archivey.internal.password._PasswordCandidates.attempt`
    describes. The winner joins the known-good passwords when it was confirmed, or
    when it was the only password there was; a candidate that only survived a probe
    while another could still be right stays out, so later units do not try it first.
    """

    def is_confirmed(result: tuple[_T, PasswordConfirmVerdict]) -> bool:
        return result[1] is PasswordConfirmVerdict.CONFIRMED

    def promote(result: tuple[_T, PasswordConfirmVerdict]) -> bool:
        return is_confirmed(result) or not passwords.is_ambiguous()

    settle = (
        None if full_check is None else lambda password, _result: full_check(password)
    )
    return passwords.attempt(
        member, probe, promote=promote, settled=is_confirmed, settle=settle
    )


def first_crc_match(expected_crc: int, items: Sequence[tuple[_T, int]]) -> _T | None:
    """Return the first item whose CRC-32 matches ``expected_crc`` (candidate order)."""
    expected = expected_crc & 0xFFFFFFFF
    for item, crc in items:
        if (crc & 0xFFFFFFFF) == expected:
            return item
    return None


class UnverifiedPasswordReadWatch(DelegatingStream):
    """Report a member stream closed before its declared digest was reached.

    Wraps the decoded member stream of an encrypted member whose password was accepted
    on a check weaker than the member's digest (a weak cheap-key check, or a confirm
    that ran out of budget). If the caller closes the stream after reading some bytes
    but before the reads reach ``size``, ``on_unverified`` runs once: those bytes may
    have decrypted under a wrong key, and nothing checked them. It receives the reason
    the digest was not reached: ``"seek"`` when a seek forfeited it, else
    ``"partial_read"``. A stream closed before any read delivered nothing to distrust,
    and a read that raised has already told the caller something is wrong; neither
    reports. A seek that raised has not: the caller can catch it and keep reading, so
    the report stays armed.

    Whether the digest is lost follows the member verifier's rule (ADR 0014). The inner
    is asked first (``ask_digest_intact``), so a watch above the verifier gets its
    answer. A watch below it (the verifier wraps this stream) applies the same rule to
    what passes through, with its own hashing frontier (the end of the reads contiguous
    from 0): a position past it is lost, unless it is at or past ``size`` with no read
    past the frontier yet (the verifier's conclusion reads the gap). A read that starts
    past the frontier leaves it there, and a seek back to it or behind it, then reads on
    to ``size``, gets the digest back. A forward seek the verifier keeps the digest
    across reaches this stream as reads up to the target. Pass ``seek_forfeits=False``
    for a digest that survives seeks (the WinZip AES HMAC, which the decrypt stage
    completes over the ciphertext at the end): only a read that reaches ``size`` counts
    there, wherever it started.

    ``key_in_doubt`` says whether the password is still unconfirmed, for the stream's
    verification level (``_verification_proofs``). Reaching ``size`` does not clear it:
    the digest can run on a later read (the over-run probe drives the WinZip AES HMAC),
    and only its match, which the layers below report, proves the key.
    """

    readinto_passthrough = False

    def __init__(
        self,
        inner: BinaryIO,
        *,
        size: int,
        on_unverified: Callable[[str], None],
        seek_forfeits: bool = True,
        key_in_doubt: Callable[[], bool] | None = None,
    ) -> None:
        # Set before the base constructor, which ``close()`` must survive: IOBase's
        # finalizer calls ``close()`` on an instance whose ``__init__`` raised.
        self._watch_size = size
        self._on_unverified: Callable[[str], None] | None = on_unverified
        self._watch_pos = 0
        self._watch_furthest = 0
        self._watch_hashed = 0
        self._delivered = False
        self._reached = size <= 0
        self._forfeited = False
        self._seek_forfeits = seek_forfeits
        self._key_in_doubt = key_in_doubt
        super().__init__(inner)

    def _verification_proofs(self) -> VerificationProofs:
        below = ask_verification_proofs(self._inner)
        # A watch exists because a weak check took the password: without a callable
        # to say otherwise, the key stays in doubt.
        if self._key_in_doubt is not None and not self._key_in_doubt():
            return below
        return VerificationProofs(key_in_doubt=True).combine(below)

    def _digest_lost(self) -> bool:
        """Whether a read on to the end would no longer run the digest."""
        if self._forfeited:
            return True
        if not self._seek_forfeits:
            return False
        intact = ask_digest_intact(self._inner)
        if intact is not None:
            return not intact
        if self._watch_pos <= self._watch_hashed:
            return False
        return (
            self._watch_pos < self._watch_size
            or self._watch_hashed < self._watch_furthest
        )

    def _note_position(self) -> None:
        # "Reads reached ``size``" stands for "the digest ran". That holds only for an
        # inner stream that verifies on the read reaching its declared size, not on a
        # following empty read: ``MemberVerifier`` finishes (CRC, WinZip AES HMAC,
        # over-run probe) on that read. An inner stream that deferred the check to the
        # next read would silence this report; check a new wrap target against it.
        if self._watch_pos >= self._watch_size and not self._digest_lost():
            self._reached = True

    def read(self, n: int = -1, /) -> bytes:
        start = self._watch_pos
        try:
            data = super().read(n)
        except BaseException:
            # The failure is the caller's signal; the close-time report would add
            # nothing to it.
            self._on_unverified = None
            raise
        if data:
            self._delivered = True
            self._watch_pos += len(data)
            self._watch_furthest = max(self._watch_furthest, self._watch_pos)
            if start <= self._watch_hashed:
                self._watch_hashed = max(self._watch_hashed, self._watch_pos)
            # A read that starts past the frontier skipped the bytes before ``start``;
            # the frontier stays. A verifier below answers for itself (it may have read
            # them through), and ``_digest_lost`` asks it first.
            self._note_position()
        # EOF, seen or read through (``read(-1)`` returns at it). This assumes the
        # inner has run its end-of-stream check by then, and a mismatch would have
        # raised above: true of a stream whose ``read(-1)`` reads on to its empty
        # read (a ZIP pass's member stream, whose check runs there), and of one
        # that checks on reaching its size. As for ``_note_position``, check a new
        # wrap target against it.
        if (n < 0 or (not data and n != 0)) and not self._digest_lost():
            self._reached = True
        return data

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        try:
            position = super().seek(offset, whence)
        except BaseException:
            # Unlike a failed read, a failed seek need not end the stream: the caller
            # can catch it and read on, so the report stays armed.
            self._note_failed_seek()
            raise
        self._note_moved(position)
        return position

    def _note_moved(self, position: int) -> None:
        """Track a seek: a rewind to 0 re-arms the digest, as the member's verifier does."""
        if position == 0:
            self._forfeited = False
            self._watch_furthest = 0
            self._watch_hashed = 0
        self._watch_pos = position

    def nearest_resume_offset(self, target: int) -> int | None:
        # Below a member's verifier, which asks this to decide whether a forward seek
        # decodes the skipped bytes anyway; the offsets are the inner's.
        return ask_resume_offset(self._inner, target)

    def _note_failed_seek(self) -> None:
        """Keep the position true to where a seek that raised left the stream.

        A refused seek (a negative position) moves nothing, and the digest is intact.
        A seek can also raise after it moved (``ArchiveStream._note_raised_seek``), and
        then it counts as a seek. When the position cannot be read, the stream may
        have moved and no later read can be placed, so the digest counts as forfeited
        even where seeks do not forfeit it.
        """
        try:
            position = self.tell()
        except Exception:  # noqa: BLE001 - the seek's own error propagates instead
            self._forfeited = True
            return
        if position == self._watch_pos:
            return
        self._note_moved(position)

    def close(self) -> None:
        if self.closed:
            return
        callback = self._on_unverified
        self._on_unverified = None
        # Asked before the inner closes, while it can still answer.
        reason = "partial_read"
        if callback is not None and self._delivered and not self._reached:
            try:
                lost = self._digest_lost()
            except Exception:  # noqa: BLE001 - a report at close must not raise
                lost = self._forfeited
            reason = "seek" if lost else "partial_read"
        try:
            super().close()
        finally:
            if callback is not None and self._delivered and not self._reached:
                callback(reason)
